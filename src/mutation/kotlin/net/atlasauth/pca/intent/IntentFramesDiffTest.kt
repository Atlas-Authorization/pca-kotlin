package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of frame and side-effect constraints. */
@Suppress("UNCHECKED_CAST")
class IntentFramesDiffTest {
    private val m = "ref-intent-frames"

    private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    @Test fun stateDigest() = OracleCases.each(m, "stateDigest") { a -> IntentFrames.stateDigest(a[0]) }

    @Test fun snapshotState() = OracleCases.each(m, "snapshotState") { a -> IntentFrames.snapshotState(mp(a[0]), a.size < 2 || a[1] != false) }

    @Test fun checkFrame() = OracleCases.each(m, "checkFrame") { a -> IntentFrames.checkFrame(a[0], a[1], a[2], a[3], mp(a[4])) }

    @Test fun applyScenario() = OracleCases.each(m, "applyScenario") { a ->
        val l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(a[0]), MapLearnerOptions.fromJson(a[1]))
        for (xo in ls(a[2])) {
            val x = mp(xo)
            l.observe(IntentOmega.outcomeFromJson(x), IntentOmega.dbl(x["y"]).toInt(), x["source"] as String, null)
        }
        val result = IntentFrames.applyFrameReport(l, IntentOmega.outcomeFromJson(a[3]), a[4])
        val r = l.metrics() // the reference reads the metrics after the report is applied
        linkedMapOf<String, Any?>(
            "result" to result,
            "metrics" to linkedMapOf<String, Any?>(
                "residualRisk" to r.residualRisk, "burden" to r.burden, "uncertainty" to r.uncertainty, "entropyBits" to r.entropyBits,
                "log2VersionSpace" to r.log2VersionSpace, "disagreementMass" to r.disagreementMass, "meanHarm" to r.meanHarm,
                "questions" to r.questions.toDouble(), "conflicts" to r.conflicts.toDouble(),
            ),
        )
    }
}
