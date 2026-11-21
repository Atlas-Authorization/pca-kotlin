package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.Keys
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over the signed evolution records between two versions of a pack. */
@Suppress("UNCHECKED_CAST")
class ActionsEvolveDiffTest {
    private val M = "ref-actions-evolve"
    private val CORE = Actions.CORE_REGISTRY

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun evolutionRecords() = OracleCases.each(M, "evolutionRecords") { a ->
        val c = a[3] as Boolean
        ActionEvolve.evolutionRecords(a[0] as String, l(a[1]), l(a[2]), CORE) { _ -> c }
    }

    @Test fun signEvolution() = OracleCases.each(M, "signEvolution") { a ->
        ActionEvolve.signEvolution(l(a[0]), a[1] as String, Keys.unb64u(m(a[2])["\$bytes"] as String))
    }

    @Test fun evolutionError() = OracleCases.each(M, "evolutionError") { a ->
        val c = a[5] as Boolean
        ActionEvolve.evolutionError(a[0] as String, l(a[1]), l(a[2]), l(a[3]), l(a[4]), CORE) { _ -> c }
    }
}
