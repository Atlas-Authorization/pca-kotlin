package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of classifier-error calibration and the classifier-aware residual risk. */
@Suppress("UNCHECKED_CAST")
class IntentClassifierKitDiffTest {
    private val m = "ref-intent-classifier"

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

    @Test fun calibrate() = OracleCases.each(m, "calibrate") { a ->
        IntentClassifierKit.calibrateConfusion(ls(a[0]), ls(a[1]), if (a.size > 2) IntentOmega.dbl(a[2]) else null)
    }

    @Test fun confusionDigest() = OracleCases.each(m, "confusionDigest") { a -> IntentClassifierKit.confusionDigest(mp(a[0])) }

    @Test fun publishedErrorRate() = OracleCases.each(m, "publishedErrorRate") { a -> IntentClassifierKit.publishedErrorRate(mp(a[0])) }

    @Test fun classifierCardNote() = OracleCases.each(m, "classifierCardNote") { a -> IntentClassifierKit.classifierCardNote(a[0] as String, mp(a[1])) }

    @Test fun riskArrays() = OracleCases.each(m, "riskArrays") { a ->
        val op = a[0] as String
        val arr = mp(a[1])
        if (op == "risk") IntentClassifierKit.classifierRisk(arr)
        else if (op == "sound") IntentClassifierKit.labelSound(arr)
        else IntentClassifierKit.labelSoundBound(arr, IntentOmega.dbl(a[2]))
    }

    @Test fun awareScenario() = OracleCases.each(m, "awareScenario") { a ->
        IntentClassifierKit.classifierAwareResidualRisk(make(a[0], a[1], a[2]), ls(a[3]))
    }

    @Test fun jitScenario() = OracleCases.each(m, "jitScenario") { a ->
        IntentClassifierKit.classifierJitCells(make(a[0], a[1], a[2]), mp(a[3]), IntentOmega.dbl(a[4]))
    }
}
