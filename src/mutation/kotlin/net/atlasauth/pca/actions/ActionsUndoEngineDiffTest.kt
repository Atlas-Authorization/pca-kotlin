package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the confirmation-gated undo planner. */
@Suppress("UNCHECKED_CAST")
class ActionsUndoEngineDiffTest {
    private val MOD = "ref-actions-undo-engine"

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun plan() = OracleCases.each(MOD, "undoPlan") { a -> ActionUndoEngine.undoEngine(l(a[0]), a[1], null).plan(m(a[2])) }

    @Test fun attested() = OracleCases.each(MOD, "attested") { a -> ActionUndoEngine.attestationVerifier(a[1], Actions.CORE_REGISTRY)(m(a[0])) }
}
