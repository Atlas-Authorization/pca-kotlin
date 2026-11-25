package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of signed runtime observations and the trust ramp with its drift freeze. */
@Suppress("UNCHECKED_CAST")
class IntentRampDiffTest {
    private val m = "ref-intent-ramp"

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

    private fun dnum(x: Map<String, Any?>, k: String): Double? = if (x[k] == null) null else IntentOmega.dbl(x[k])

    @Test fun signObservation() = OracleCases.each(m, "signObservation") { a -> IntentObservation.signIntentObservation(mp(a[0]), Keys.unb64u(a[1] as String)) }

    @Test fun verifyObservation() = OracleCases.each(m, "verifyObservation") { a ->
        val opts = mp(a[1])
        val pins = if (opts["pqPins"] == null) null else mp(opts["pqPins"])
        IntentObservation.verifyIntentObservation(a[0], opts["expectedSigner"] as String?, pins)
    }

    @Test fun rampScenario() = OracleCases.each(m, "rampScenario") { a ->
        val d = mp(a[3])
        val ramp = IntentTrustRamp(make(a[0], a[1], a[2]), dnum(d, "rho0"), dnum(d, "rho1"), dnum(d, "h"))
        val out = ArrayList<Any?>()
        // the reference's state op returns the live queue array, serialised only at the end: every state op of a generation shows
        // the queue as it stands when that generation ends (a rebase starts a new array)
        var gen = ArrayList<Any?>()
        for (oo in ls(a[4])) {
            val op = mp(oo)
            when (op["op"] as String) {
                "record" -> out.add(ramp.record(IntentOmega.outcomeFromJson(op["outcome"]), op["signal"] as String?).toJson())
                "observe" -> {
                    val c = mp(op["ctx"])
                    val trusted = ls(c["trustedSigners"]).map { it as String }
                    val ver = if (c["verify"] == null) LinkedHashMap<String, Any?>() else mp(c["verify"])
                    val pins = if (ver["pqPins"] == null) null else mp(ver["pqPins"])
                    out.add(ramp.recordObservation(op["obs"], c["mapDigest"] as String, trusted, ver["expectedSigner"] as String?, pins))
                }
                "rebase" -> {
                    gen.addAll(ramp.pending())
                    gen = ArrayList()
                    ramp.rebase(make(op["omega"], op["mapOpts"], op["observations"]))
                    out.add(linkedMapOf("frozen" to ramp.frozen(), "pending" to ramp.pending().size.toDouble()))
                }
                else -> out.add(linkedMapOf("frozen" to ramp.frozen(), "pending" to gen, "drift" to ramp.drift.state().toJson()))
            }
        }
        gen.addAll(ramp.pending())
        val log = ramp.log.map { it.toJson() }
        val lm = ramp.learner().metrics()
        val metrics = linkedMapOf<String, Any?>(
            "residualRisk" to lm.residualRisk, "burden" to lm.burden, "uncertainty" to lm.uncertainty, "entropyBits" to lm.entropyBits,
            "log2VersionSpace" to lm.log2VersionSpace, "disagreementMass" to lm.disagreementMass, "meanHarm" to lm.meanHarm,
            "questions" to lm.questions.toDouble(), "conflicts" to lm.conflicts.toDouble(),
        )
        val end = linkedMapOf("log" to log, "frozen" to ramp.frozen(), "pending" to ramp.pending(), "metrics" to metrics)
        listOf(out, end)
    }
}
