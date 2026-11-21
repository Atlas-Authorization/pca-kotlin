package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.AttestUtil
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of trajectory intent: the augmented space, the lift, the step rule and the wallet's default accumulators. */
@Suppress("UNCHECKED_CAST")
class IntentTrajectoryDiffTest {
    private val m = "ref-intent-trajectory"

    private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    private fun ints(a: IntArray): List<Any?> = a.map { it.toDouble() }

    private fun schemaOf(a: List<Any?>, i: Int): Any? = if (a.size > i) a[i] else null

    @Test fun dimKindOf() = OracleCases.each(m, "dimKindOf") { a -> IntentTrajectory.dimKindOf(a[0] as String) }

    @Test fun accDimPath() = OracleCases.each(m, "accDimPath") { a -> IntentTrajectory.accDimPath(a[0] as String) }

    @Test fun monDimPath() = OracleCases.each(m, "monDimPath") { a -> IntentTrajectory.monDimPath(a[0] as String) }

    @Test fun trajectoryHarmRange() = OracleCases.each(m, "trajectoryHarmRange") { a ->
        IntentTrajectory.trajectoryHarmRange(IntentOmega.dbl(a[0]), IntentOmega.dbl(a[1]))
    }

    @Test fun augment() = OracleCases.each(m, "augment") { a ->
        IntentOmega.omegaToJson(IntentTrajectory.augmentOmega(IntentOmega.omegaFromJson(a[0]), mp(a[1]), if (a.size > 2) mp(a[2]) else null))
    }

    @Test fun liftScenario() = OracleCases.each(m, "liftScenario") { a ->
        val tilde = IntentTrajectory.augmentOmega(IntentOmega.omegaFromJson(a[0]), mp(a[1]), mp(a[2]))
        val lifted = IntentTrajectory.liftAction(tilde, mp(a[1]), ls(a[3]), mp(a[4]), schemaOf(a, 5))
        val out = LinkedHashMap<String, Any?>()
        out["lifted"] = if (lifted == null) null else IntentOmega.outcomeToJson(lifted)
        val c = if (lifted == null) null else IntentTrajectory.liftedCell(tilde, lifted)
        out["cell"] = if (c == null) null else linkedMapOf<String, Any?>("verb" to c.vs.verb, "cell" to ints(c.cell))
        out
    }

    private fun grant(g: String): (String, IntArray) -> Boolean = when (g) {
        "all" -> ({ _, _ -> true })
        "none" -> ({ _, _ -> false })
        "cell0" -> ({ _, c -> c.all { it == 0 } })
        else -> ({ _, c -> c[0] <= 1 })
    }

    @Test fun stepScenario() = OracleCases.each(m, "stepScenario") { a ->
        val tilde = IntentTrajectory.augmentOmega(IntentOmega.omegaFromJson(a[0]), mp(a[1]), mp(a[2]))
        val s = IntentTrajectory.stepTrajectory(tilde, mp(a[1]), ls(a[3]), mp(a[4]), grant(a[5] as String), schemaOf(a, 6))
        linkedMapOf<String, Any?>("admitted" to s.admitted, "history" to s.history, "lifted" to s.lifted?.let { IntentOmega.outcomeToJson(it) })
    }

    @Test fun defaultAccumulators() = OracleCases.each(m, "defaultAccumulators") { a ->
        val o = mp(a[1])
        IntentTrajectory.defaultAccumulators(
            a[0], IntentOmega.dbl(o["spendDomainMax"]), if (o["questionCap"] == null) null else IntentOmega.dbl(o["questionCap"]),
            if (o["holder"] == null) null else mp(o["holder"]),
        )
    }

    @Test fun describeAccCell() = OracleCases.each(m, "describeAccCell") { a ->
        val fmt: ((Double) -> String)? = if ("bracket" == a[4]) ({ x -> "[" + AttestUtil.jsNumString(x) + "]" }) else null
        IntentTrajectory.describeAccCell(
            IntentOmega.dimFromJson(a[0]) as IntentOmega.NumDim, IntentOmega.dbl(a[1]).toInt(), a[2] as String,
            if (a[3] == null) null else IntentOmega.dbl(a[3]), fmt,
        )
    }
}
