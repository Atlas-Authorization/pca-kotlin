package net.atlasauth.pca.verifier

import java.io.File
import net.atlasauth.pca.verifier.goalrunner.replay
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Runner of the pca-goal conformance vectors (goal corpus `conformance/goal`, selector corpus `conformance/goal-select`; under
 * `packages/pca-conformance/vectors` in the monorepo): goal digest, lowered policy digest, decision + witness of every probe, the
 * helper vectors, and the native expansion of trait selectors. The semantics are the shared runner
 * (packages/pca-conformance/runners/goal/kotlin/Run.kt; goalrunner/GoalRunner.kt is its generated copy), so every language replays
 * one reference: ZERO disagreements, and the corpus sizes are pinned so a truncated vendoring fails.
 */
class GoalVectorsTest {
    @Test
    fun everyGoalVectorAgreesWithTheReference() {
        val (n, probes, bad) = replay(ParityVectors.goalDir().path)
        assertTrue("only $n goal vectors", n >= 240)
        assertTrue("only $probes probes", probes > 6000)
        assertEquals(emptyList<String>(), bad.take(20))
    }

    @Test
    fun everySelectorVectorAgreesWithTheReference() {
        val dir = File(ParityVectors.goalDir().parentFile, "goal-select")
        assertTrue("the selector vectors are missing: $dir", dir.isDirectory)
        val (n, probes, bad) = replay(dir.path)
        assertTrue("only $n selector vectors", n >= 48)
        assertTrue("only $probes probes", probes > 1000)
        assertEquals(emptyList<String>(), bad.take(20))
    }
}
