package net.atlasauth.pca.controlevals

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The example blue control protocol (with data-flow governance and the behavioral immune system) against the reference's own recorded episodes and
 * evaluations: the native protocol decides every action of every recorded run exactly as the TypeScript stack did (outcome, control, risk, threat
 * level, reason, budget), so the whole transcript and the aggregated report compare equal.
 */
@Suppress("UNCHECKED_CAST")
class ControlEvalsExampleDiffTest {
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

    @Test fun episodesAreDecidedLikeTheReference() {
        val agent = ControlEvalsExample.buildExampleAgent()
        OracleCases.each(M, "runEpisode") { a ->
            val spec = m(a[0])
            ControlEvals.runEpisode(red(spec["red"] as String), ControlEvalsExample.exampleBlue(agent), env(spec["env"] as String), d(spec["seed"]))
        }
    }

    @Test fun evaluationsAreScoredLikeTheReference() {
        val agent = ControlEvalsExample.buildExampleAgent()
        OracleCases.each(M, "controlEval") { a ->
            val spec = m(a[0])
            val reds = if (spec["reds"] is List<*>) l(spec["reds"]).map { red(it as String) } else null
            ControlEvals.controlEval(reds, ControlEvalsExample.exampleBlue(agent), env(spec["env"] as String), spec["episodes"], spec["seed"])
        }
    }

    @Test fun exampleControlEvalIsDeterministicAndScoresEveryStrategy() {
        val r = ControlEvalsExample.exampleControlEval()
        assertEquals(8L * ControlEvals.EXAMPLE_RED_POLICIES.size, d(r["episodes"]).toLong())
        assertEquals(ControlEvals.EXAMPLE_RED_POLICIES.size, (r["byStrategy"] as Map<String, Any?>).size)
        assertEquals(Json.canonicalize(r), Json.canonicalize(ControlEvalsExample.exampleControlEval()))
        assertThrows(IllegalArgumentException::class.java) { ControlEvalsExample.exampleControlEval(0L, 1L, null) }
    }
}
