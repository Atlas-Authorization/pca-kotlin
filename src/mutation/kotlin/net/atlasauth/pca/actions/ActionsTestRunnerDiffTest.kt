package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the executable examples and property checks of an action pack. */
@Suppress("UNCHECKED_CAST")
class ActionsTestRunnerDiffTest {
    private val MOD = "ref-actions-test-runner"
    private val CORE = Actions.CORE_REGISTRY

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun decide() = OracleCases.each(MOD, "decideExample") { a -> ActionTestRunner.decideExample(m(a[0]), m(a[1]), CORE, l(a[2])) }

    @Test fun runTests() = OracleCases.each(MOD, "runDefTests") { a ->
        ActionTestRunner.runDefTests(l(a[0]), CORE, a[1]?.let { (it as Json.Num).raw.toDouble().toInt() }, null)
    }

    @Test fun text() = OracleCases.each(MOD, "testText") { a -> ActionTestRunner.testText(m(a[0])) }
}
