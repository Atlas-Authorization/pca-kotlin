package net.atlasauth.pca.verifier

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rule 21's report trigger, each operand ALONE (reference intent-v2.ts:646-647): `tighten` is reported iff the envelope has
 * `tighten`, or a `model_polarity` (envelope, or the verifier policy, `strict` included), or a grant-side where reads a
 * model-derived path. With none of them a PCActn verifies as before (no check).
 */
class Kill05R2TightenTriggerTest {
    private fun grant(extra: String) = ParityVectors.obj(
        """{"caveats":[{"type":"envelope","goal_commit":"g","caveats":[],"agent_binding":{},
        "risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,"theta2":1,"kappa":1,"lambda":0,"rho":0,"bMax":0},
        $extra "predicates":[{"verb":"*"}]}]}""",
    )
    private val p = ParityVectors.obj("""{"aud":"a","action":{"verb":"v","resource":"r"}}""")

    private fun names(extra: String, ctx: IntentV2.Context?) = IntentV2.decide(p, grant(extra), ctx, 0L).checks.map { "${it.name}:${it.ok}" }

    @Test
    fun envelopeTightenAloneReportsTighten() = assertEquals(listOf("tighten:true"), names(""""tighten":[],""", null))

    @Test
    fun envelopePolarityAloneReportsTighten() = assertEquals(listOf("tighten:true"), names(""""model_polarity":"legacy",""", null))

    @Test
    fun policyStrictAloneReportsTighten() =
        assertEquals(listOf("tighten:true"), names("", IntentV2.Context.fromJson(ParityVectors.obj("""{"policy":{"model_polarity":"strict"}}"""))))

    @Test
    fun noTriggerReportsNothing() {
        assertTrue(names("", null).isEmpty())
        assertTrue(names("", IntentV2.Context.fromJson(ParityVectors.obj("""{"policy":{}}"""))).isEmpty())
    }
}
