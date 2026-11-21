package net.atlasauth.pca.intent

import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the layered lattice over a task learner and organisation layers learned from maps. */
@Suppress("UNCHECKED_CAST")
class IntentLatticeDiffTest {
    private val m = "ref-intent-lattice"

    private fun mp(o: Any?): Map<String, Any?> = o as Map<String, Any?>

    private fun ls(o: Any?): List<Any?> = o as List<Any?>

    @Test fun latticeScenario() = OracleCases.each(m, "latticeScenario") { a ->
        val l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(a[0]), MapLearnerOptions.fromJson(a[1]))
        for (xo in ls(a[2])) {
            val x = mp(xo)
            l.observe(IntentOmega.outcomeFromJson(x), IntentOmega.dbl(x["y"]).toInt(), x["source"] as String, null)
        }
        val c = IntentLayers.ceilingAdmitters(mp(a[3]))
        linkedMapOf(
            "view" to IntentLattice.latticeView(l, c),
            "decisions" to ls(a[4]).map { IntentLattice.decideOutcomeLayers(l, c, IntentOmega.outcomeFromJson(it)) },
        )
    }

    @Test fun orgScenario() = OracleCases.each(m, "orgScenario") { a -> IntentLattice.orgLayerFromMaps(ls(a[0]), mp(a[1])) }
}
