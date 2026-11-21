package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of the world, provenance and classifier dimensions. */
class IntentWorldDiffTest {
    private val m = "ref-intent-world"

    private fun map(o: Any?): Map<String, Any?> = IntentOmega.obj(o)

    private fun nums(o: Any?): List<Double>? = if (o == null) null else IntentOmega.arr(o).map { IntentOmega.dbl(it) }

    private fun strs(o: Any?): List<String> = IntentOmega.arr(o).map { it as String }

    @Test fun worldDim() = OracleCases.each(m, "worldDim") { a ->
        val s = map(a[1])
        IntentOmega.dimToJson(IntentWorld.worldDim(a[0] as String, IntentOmega.dbl(s["lo"]), IntentOmega.dbl(s["hi"]), nums(s["cuts"]), s["dist"] as String?))
    }

    @Test fun excessDim() = OracleCases.each(m, "excessDim") { a -> IntentOmega.dimToJson(IntentWorld.excessDim(a[0] as String, IntentOmega.dbl(a[1]), nums(a[2]))) }

    @Test fun optimalityCondition() = OracleCases.each(m, "optimalityCondition") { a ->
        IntentWorld.optimalityCondition(a[0] as String, if (a.size > 1) IntentOmega.dbl(a[1]) else 0.0)
    }

    @Test fun provenanceDim() = OracleCases.each(m, "provenanceDim") { a -> IntentOmega.dimToJson(IntentWorld.provenanceDim(a[0] as String)) }

    @Test fun classifierDim() = OracleCases.each(m, "classifierDim") { a -> IntentOmega.dimToJson(IntentWorld.classifierDim(a[0] as String, strs(a[1]))) }

    @Test fun withDims() = OracleCases.each(m, "withDims") { a ->
        IntentOmega.omegaToJson(IntentWorld.withDims(IntentOmega.omegaFromJson(a[0]), a[1] as String, IntentOmega.arr(a[2]).map { IntentOmega.dimFromJson(it) }))
    }

    @Test fun liftOutcome() = OracleCases.each(m, "liftOutcome") { a ->
        IntentOmega.outcomeToJson(IntentWorld.liftOutcome(IntentOmega.outcomeFromJson(a[0]), map(a[1]), strs(a[2])))
    }
}
