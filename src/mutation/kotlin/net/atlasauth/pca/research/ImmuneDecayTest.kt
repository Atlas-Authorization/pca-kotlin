package net.atlasauth.pca.research

import net.atlasauth.pca.verifier.IntentJs
import net.atlasauth.pca.verifier.Json
import org.junit.Assert.assertEquals
import org.junit.Test

/** The immune decay is made of exactly rounded steps (0.5 per half-life, 2^(-1/1024) per 1/1024th), and a policy whose kappa or theta is not a number widens. */
class ImmuneDecayTest {
    private fun stepUpsAfter(dtMs: Long): Double {
        val st = LinkedHashMap(Immune.initialState())
        st["stepUps"] = Json.Num("1")
        st["lastAt"] = Json.Num("0")
        st["seeded"] = true
        val r = Immune.observe(st, linkedMapOf<String, Any?>("r" to Json.Num("0"), "at" to Json.Num(dtMs.toString())))
        return IntentJs.num(r["stepUps"])!!
    }

    @Test fun aWholeHalfLifeHalvesAndASmallestStepMultipliesByTheStepFactor() {
        assertEquals(0.5, stepUpsAfter(3_600_000L), 0.0)
        assertEquals(0.25, stepUpsAfter(7_200_000L), 0.0)
        assertEquals(0.9993233275026507, stepUpsAfter(3516L), 0.0) // u = 1: one step
        assertEquals(1.0, stepUpsAfter(3515L), 0.0) // under a step: no decay
    }

    @Test fun aKappaOrThetaThatIsNotANumberIsAViolation() {
        val base = emptyMap<String, Any?>()
        for (bad in listOf<Any?>(null, true, "2")) {
            for (k in listOf("kappa", "theta1", "theta2")) {
                val adapted = linkedMapOf<String, Any?>("kappa" to Json.Num("2"), "theta1" to Json.Num("0.1"), "theta2" to Json.Num("0.2"))
                adapted[k] = bad
                assertEquals("$k $bad", "kappa and theta must be numbers", Immune.noWidenViolation(base, adapted))
            }
        }
    }
}
