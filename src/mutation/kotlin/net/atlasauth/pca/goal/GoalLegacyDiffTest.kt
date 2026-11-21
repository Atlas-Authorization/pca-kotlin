package net.atlasauth.pca.goal

import net.atlasauth.pca.verifier.Json
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle of liftLegacy (default catalog). */
@Suppress("UNCHECKED_CAST")
class GoalLegacyDiffTest {
    private fun m(o: Any?): Map<String, Any?>? = if (o is Map<*, *>) o as Map<String, Any?> else null

    private fun lng(o: Any?): Long? = if (o == null) null else (o as Json.Num).raw.toLong()

    @Test fun liftLegacy() = OracleCases.each("ref-goal-legacy", "liftLegacy") { a ->
        val perms = a[0]
        if (perms !is Map<*, *>) throw IllegalArgumentException("permissions must be an object")
        GoalLegacy.liftLegacy(m(perms)!!, m(a[1]), null, a[2] as String, lng(a[3]), lng(a[4]), a[5] as String?)
    }
}
