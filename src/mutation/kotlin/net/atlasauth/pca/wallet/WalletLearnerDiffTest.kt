package net.atlasauth.pca.wallet

import net.atlasauth.pca.intent.IntentLearner
import net.atlasauth.pca.intent.IntentOmega
import net.atlasauth.pca.intent.IntentOmega.Omega
import net.atlasauth.pca.intent.IntentOmega.Outcome
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

@Suppress("UNCHECKED_CAST")
class WalletLearnerDiffTest {
    private val M = "ref-wallet-learner-java"

    private fun outcome(o: Any?): Outcome {
        val m = IntentOmega.obj(o)
        return IntentOmega.outcomeFromJson(mapOf("verb" to m["verb"], "values" to m["values"]))
    }

    private fun ints(a: IntArray): List<Any?> = a.map { it.toDouble() }

    private fun learner(omega: Omega, obs: Any?): IntentLearner {
        val l = IntentLearner(omega)
        for (x in IntentOmega.arr(obs)) l.observe(outcome(x), IntentOmega.dbl(IntentOmega.obj(x)["y"]).toInt())
        return l
    }

    @Test fun view() = OracleCases.each(M, "view") { a ->
        val omega = IntentOmega.omegaFromJson(a[0])
        val l = learner(omega, a[1])
        val ceil = a[2]
        val v = if (ceil == null) WalletLearner.learnerView(l) else WalletLearner.learnerView(l) { _, idx -> idx[0] <= IntentOmega.dbl(ceil) }
        val cells = ArrayList<Any?>()
        for (vs in omega.verbs) {
            val t = IntentOmega.verbCellCount(vs)
            var f = 0
            while (f < t) {
                val idx = IntentOmega.decodeCell(vs, f.toDouble())
                cells.add(listOf(vs.verb, ints(idx), v.p(vs.verb, idx), v.vetoed(vs.verb, idx), v.outsideCeiling(vs.verb, idx)))
                f++
            }
        }
        val confirmed = ArrayList<Any?>()
        for (m in v.confirmed()) confirmed.add(linkedMapOf("verb" to m["verb"], "idx" to (m["idx"] as List<Any?>).map { (it as Number).toDouble() }))
        linkedMapOf("cells" to cells, "confirmed" to confirmed)
    }

    @Test fun probe() = OracleCases.each(M, "probe") { a ->
        WalletLearner.learnerView(IntentLearner(IntentOmega.omegaFromJson(a[0]))).p(a[1] as String, intArrayOf(0, 0))
    }

    @Test fun priorAdmittedPpm() = OracleCases.each(M, "ppm") { a ->
        val omega = IntentOmega.omegaFromJson(a[0])
        val base = IntentLearner.LearnerOptions.fromJson(a[1])
        val obs = ArrayList<IntentLearner.Observation>()
        for (x in IntentOmega.arr(a[2])) obs.add(IntentLearner.Observation(IntentOmega.obj(x)["verb"] as String, outcome(x).values, IntArray(0),
            IntentOmega.dbl(IntentOmega.obj(x)["y"]).toInt(), "elicitation", null))
        val mix = WalletPopulation.populationPrior(a[3] as Map<String, Any?>, IntentOmega.dbl(a[4]))
        WalletLearner.priorAdmittedPpm(omega, base, obs, mix)
    }
}
