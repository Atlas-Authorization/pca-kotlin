package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of effect verification feeding back into the learner and the Monte Carlo residual risk. */
@Suppress("UNCHECKED_CAST")
class IntentOutcomeDiffTest {
    private val m = "ref-intent-outcome"

    private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    private fun make(omega: Any?, mapOpts: Any?, obs: Any?): IntentLearner {
        val l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts))
        for (xo in ls(obs)) {
            val x = mp(xo)
            l.observe(IntentOmega.outcomeFromJson(x), IntentOmega.dbl(x["y"]).toInt(), x["source"] as String, null)
        }
        return l
    }

    @Test fun verifyScenario() = OracleCases.each(m, "verifyScenario") { a ->
        val l = make(a[0], a[1], a[2])
        val result = IntentOutcome.verifyOutcome(l, IntentOmega.outcomeFromJson(a[3]), mp(a[4]), if (a.size > 5) ls(a[5]) else null)
        val r = l.metrics()
        val metrics = linkedMapOf<String, Any?>(
            "residualRisk" to r.residualRisk, "burden" to r.burden, "uncertainty" to r.uncertainty, "entropyBits" to r.entropyBits,
            "log2VersionSpace" to r.log2VersionSpace, "disagreementMass" to r.disagreementMass, "meanHarm" to r.meanHarm,
            "questions" to r.questions.toDouble(), "conflicts" to r.conflicts.toDouble(),
        )
        linkedMapOf("result" to result, "metrics" to metrics)
    }

    @Test fun mcScenario() = OracleCases.each(m, "mcScenario") { a ->
        IntentOutcome.estimateResidualRiskMC(make(a[0], a[1], a[2]), IntentOmega.dbl(a[3]).toInt(), IntentOmega.dbl(a[4]))
    }
}
