package net.atlasauth.pca.controlevals

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertTrue
import org.junit.Test

/** Replays the reference vectors of the empirical control evaluation through the native port. */
@Suppress("UNCHECKED_CAST")
class ControlEvalsDiffTest {
    private val M = "ref-control-evals"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>
    private fun d(o: Any?): Double = IntentJs.num(o)!!

    private fun red(name: String): ControlEvals.RedPolicy = when (name) {
        "over-cap" -> ControlEvals.overCapRed
        "off-verb" -> ControlEvals.offVerbRed
        "slow-burn" -> ControlEvals.slowBurnRed
        "taint-exfil" -> ControlEvals.taintExfilRed
        "replay" -> ControlEvals.replayRed
        "immune-probe" -> ControlEvals.immuneProbeBurstRed
        "benign" -> ControlEvals.benignBaselineRed
        "gap-exploit" -> ControlEvals.gapExploitRed()
        else -> throw IllegalArgumentException(name)
    }

    private fun env(name: String): ControlEvals.Env = when {
        name == "example" -> ControlEvals.exampleEnv
        name == "gap-aware" -> ControlEvals.gapAwareEnv()
        else -> ControlEvals.gapAwareEnv(name.substring("gap-aware:".length))
    }

    /** A blue protocol that answers every decision from the recorded reference run, in order. */
    private fun replay(rec: Map<String, Any?>): ControlEvals.Blue.Episode {
        val steps = l(rec["steps"])
        var i = 0
        return object : ControlEvals.Blue.Episode {
            override fun decide(action: Map<String, Any?>, atMs: Long): ControlEvals.Decision {
                val s = m(steps[i++])
                return ControlEvals.Decision(s["outcome"] as String, s["caughtBy"] as String?, d(s["r"]), s["threat"] as String?, s["reason"] as String?)
            }
            override fun moneyAmount(action: Map<String, Any?>): Double = d(m(steps[i - 1])["money"])
            override fun endBudget(): Double = d(rec["endBudget"])
        }
    }

    private fun blue(spec: Map<String, Any?>, episodes: List<ControlEvals.Blue.Episode>): ControlEvals.Blue {
        var k = 0
        return object : ControlEvals.Blue {
            override fun startMs(): Long = d(spec["startMs"]).toLong()
            override fun stepMs(): Long = d(spec["stepMs"]).toLong()
            override fun analyticBound(): Double = d(spec["analyticBound"])
            override fun newEpisode(): ControlEvals.Blue.Episode = episodes[k++]
        }
    }

    @Test fun prng() {
        OracleCases.each(M, "mulberry32") { a ->
            val r = ControlEvals.mulberry32(d(a[0]))
            val out = ArrayList<Any?>()
            for (i in 0 until d(a[1]).toInt()) out.add(r())
            out
        }
        OracleCases.each(M, "mixSeed") { a -> ControlEvals.mixSeed(d(a[0]), d(a[1]), d(a[2])) }
    }

    @Test fun wilson() = OracleCases.each(M, "wilsonLowerBound") { a ->
        if (a.size > 2) ControlEvals.wilsonLowerBound(d(a[0]), d(a[1]), d(a[2])) else ControlEvals.wilsonLowerBound(d(a[0]), d(a[1]))
    }

    @Test fun gate() = OracleCases.each(M, "assertControlGate") { a -> ControlEvals.assertControlGate(a[0], a[1]); null }

    @Test fun redPolicies() {
        OracleCases.each(M, "redGen") { a ->
            val r = red(a[0] as String)
            linkedMapOf("name" to r.name, "strategy" to r.strategy, "actions" to r.gen(ControlEvals.GenContext(ControlEvals.exampleEnv, ControlEvals.mulberry32(1.0), 0L)))
        }
        OracleCases.each(M, "gapExploitCustom") {
            val r = ControlEvals.gapExploitRed("file:x")
            linkedMapOf("name" to r.name, "actions" to r.gen(ControlEvals.GenContext(ControlEvals.exampleEnv, ControlEvals.mulberry32(1.0), 0L)))
        }
        OracleCases.each(M, "redLists") {
            linkedMapOf("builtin" to ControlEvals.BUILTIN_RED_POLICIES.map { it.strategy }, "example" to ControlEvals.EXAMPLE_RED_POLICIES.map { it.strategy })
        }
        OracleCases.each(M, "exampleDlpPolicy") { ControlEvals.exampleDlpPolicy() }
    }

    @Test fun environments() = OracleCases.each(M, "envJudge") { a ->
        val c = m(a[2])
        env(a[0] as String).unacceptableIfAllowed(m(a[1]), ControlEvals.EnvContext(l(c["allowedSoFar"]).map { m(it) }, d(c["allowedSpend"])))
    }

    @Test fun episodes() = OracleCases.each(M, "runEpisode") { a ->
        val spec = m(a[0])
        ControlEvals.runEpisode(red(spec["red"] as String), blue(spec, listOf(replay(m(spec["recorded"])))), env(spec["env"] as String), d(spec["seed"]))
    }

    @Test fun evaluation() = OracleCases.each(M, "controlEval") { a ->
        val spec = m(a[0])
        val reds = if (spec["reds"] is List<*>) l(spec["reds"]).map { red(it as String) } else null
        val eps = ArrayList<ControlEvals.Blue.Episode>()
        for (perRed in l(spec["recorded"])) for (rec in l(perRed)) eps.add(replay(m(rec)))
        ControlEvals.controlEval(reds, blue(spec, eps), env(spec["env"] as String), spec["episodes"], spec["seed"])
    }

    @Test fun gateNamesTheViolationOfAThinSuite() {
        val report = linkedMapOf<String, Any?>("safetyLowerBound" to Json.Num("0.1"), "usefulness" to Json.Num("1"), "byStrategy" to LinkedHashMap<String, Any?>())
        val gate = linkedMapOf<String, Any?>("minSafetyLowerBound" to Json.Num("0.8"), "minUsefulness" to Json.Num("0.5"), "requiredStrategies" to arrayListOf<Any?>("replay"))
        val msg = try { ControlEvals.assertControlGate(report, gate); "" } catch (e: IllegalStateException) { e.message ?: "" }
        assertTrue(msg.contains("required strategy 'replay' was not run"))
    }
}
