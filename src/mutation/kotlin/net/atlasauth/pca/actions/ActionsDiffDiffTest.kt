package net.atlasauth.pca.actions

import net.atlasauth.pca.verifier.Actions
import net.atlasauth.pca.verifier.OracleCases
import org.junit.Test

/** Replays the reference oracle over id patterns, profiles, effective traits and the semantic def / pack diffs. */
@Suppress("UNCHECKED_CAST")
class ActionsDiffDiffTest {
    private val M = "ref-actions-diff"
    private val CORE = Actions.CORE_REGISTRY

    private fun m(o: Any?): Map<String, Any?> = o as Map<String, Any?>
    private fun l(o: Any?): List<Any?> = o as List<Any?>

    @Test fun idMatches() = OracleCases.each(M, "idMatches") { a -> ActionIdPattern.idMatches(a[0], a[1] as String) }

    @Test fun idPatternContains() = OracleCases.each(M, "idPatternContains") { a -> ActionIdPattern.idPatternContains(a[0], a[1]) }

    @Test fun join() = OracleCases.each(M, "join") { a -> ActionEffective.join(m(a[0]), m(a[1])) }

    @Test fun leq() = OracleCases.each(M, "leq") { a -> ActionEffective.leq(m(a[0]), m(a[1])) }

    @Test fun profileEq() = OracleCases.each(M, "profileEq") { a -> ActionEffective.profileEq(m(a[0]), m(a[1])) }

    @Test fun effective() = OracleCases.each(M, "effective") { a ->
        val c = a[1] as Boolean
        ActionEffective.effective(m(a[0]), CORE) { _ -> c }
    }

    @Test fun hintTraits() = OracleCases.each(M, "hintTraits") { a -> ActionEffective.hintTraits(m(a[0])) }

    @Test fun prulesViolations() = OracleCases.each(M, "prulesViolations") { a -> ActionEffective.prulesViolations(m(a[0])) }

    @Test fun effWithTrait() = OracleCases.each(M, "effWithTrait") { a -> ActionEffective.effWithTrait(m(a[0]), a[1] as String, CORE) }

    @Test fun requiredPrulesViolated() = OracleCases.each(M, "requiredPrulesViolated") { a -> ActionEffective.requiredPrulesViolated(m(a[0]), m(a[1])) }

    @Test fun diffDefs() = OracleCases.each(M, "diffDefs") { a ->
        val c = a.size > 2 && a[2] == true
        ActionDiff.diffDefs(m(a[0]), m(a[1]), CORE) { _ -> c }
    }

    @Test fun diffIsFree() = OracleCases.each(M, "diffIsFree") { a -> ActionDiff.diffIsFree(a[0] as String) }

    @Test fun diffDefsAuthoring() = OracleCases.each(M, "diffDefsAuthoring") { a -> ActionDefDiff.diffDefs(m(a[0]), m(a[1]), CORE) }

    @Test fun diffPacks() = OracleCases.each(M, "diffPacks") { a -> ActionDefDiff.diffPacks(l(a[0]), l(a[1]), CORE) }
}
