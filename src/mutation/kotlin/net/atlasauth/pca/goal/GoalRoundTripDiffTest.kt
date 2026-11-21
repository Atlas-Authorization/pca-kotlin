package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of the goal round-trip checks and widening mutations. */
@Suppress("UNCHECKED_CAST")
class GoalRoundTripDiffTest {
    private val M = "ref-goal-roundtrip"

    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    private fun explainer(mode: String): (List<String>) -> String = { lines ->
        if (mode == "throw") throw IllegalStateException("boom")
        GoalRoundTrip.deterministicExplain(lines)
    }

    private fun comparator(mode: String): (String, String) -> Map<String, Any?> = { _, e ->
        if (mode == "throw") throw IllegalStateException("boom")
        if (mode == "ok") mapOf("equivalent" to true)
        else if (mode == "no") mapOf("equivalent" to false)
        else mapOf("equivalent" to e.contains(mode.substring(9)))
    }

    @Test fun cardRoundTrips() = OracleCases.each(M, "cardRoundTrips") { a -> GoalRoundTrip.cardRoundTrips(m(a[0])!!) }
    @Test fun mutateGoal() = OracleCases.each(M, "mutateGoal") { a -> GoalRoundTrip.mutateGoal(m(a[0])!!, a[1] as String, m(a[2])) }

    @Test fun roundTrip() = OracleCases.each(M, "roundTrip") { a ->
        GoalRoundTrip.roundTrip(m(a[0])!!, a[1] as String, explainer(a[2] as String), comparator(a[3] as String))
    }

    @Test fun measureDetection() = OracleCases.each(M, "measureDetection") { a ->
        GoalRoundTrip.measureDetection(l(a[0]), m(a[1]), explainer(a[2] as String), comparator(a[3] as String))
    }
}
