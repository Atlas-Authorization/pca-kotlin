package net.atlasauth.pca.intent

import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference vectors of signed intent statements, their content address and the intent goal string. */
class IntentStatementDiffTest {
    private val m = "ref-intent-statement"

    @Test fun signIntent() = OracleCases.each(m, "signIntent") { a -> IntentStatement.signIntent(IntentOmega.obj(a[0]), Keys.unb64u(a[1] as String)) }

    @Test fun verifyIntent() = OracleCases.each(m, "verifyIntent") { a ->
        val opts = IntentOmega.obj(a[1])
        val pins = if (opts["pqPins"] == null) null else IntentOmega.obj(opts["pqPins"])
        IntentStatement.verifyIntent(a[0], opts["expectedSigner"] as String?, pins)
    }

    @Test fun intentRef() = OracleCases.each(m, "intentRef") { a -> IntentStatement.intentRef(a[0]) }

    @Test fun intentGoal() = OracleCases.each(m, "intentGoal") { a -> IntentStatement.intentGoal(a[0] as String, if (a.size > 1) a[1] as String? else null) }

    @Test fun parseIntentGoal() = OracleCases.each(m, "parseIntentGoal") { a -> IntentStatement.parseIntentGoal(a[0]) }
}
